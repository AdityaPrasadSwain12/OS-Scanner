#!/bin/sh
set -eu

usage() {
    echo "usage: $0 --manifest FILE --manifest-sha256 HASH --artifact-root DIR --version X.Y.Z --output-dir DIR --source-date-epoch EPOCH [--python PATH]" >&2
    exit 2
}

manifest=
manifest_sha256=
artifact_root=
version=
output_dir=
source_date_epoch=
python=python3
while [ "$#" -gt 0 ]; do
    case "$1" in
        --manifest) manifest=$2; shift 2 ;;
        --manifest-sha256) manifest_sha256=$2; shift 2 ;;
        --artifact-root) artifact_root=$2; shift 2 ;;
        --version) version=$2; shift 2 ;;
        --output-dir) output_dir=$2; shift 2 ;;
        --source-date-epoch) source_date_epoch=$2; shift 2 ;;
        --python) python=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$manifest" ] && [ -n "$manifest_sha256" ] && [ -n "$artifact_root" ] || usage
[ -n "$version" ] && [ -n "$output_dir" ] && [ -n "$source_date_epoch" ] || usage
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.][0-9]+)?$' || usage
printf '%s' "$manifest_sha256" | grep -Eq '^[0-9a-fA-F]{64}$' || usage
printf '%s' "$source_date_epoch" | grep -Eq '^[0-9]{10}$' || usage
[ "$(uname -s)" = Darwin ] || { echo 'Build the macOS package on macOS.' >&2; exit 2; }
case "$(uname -m)" in
    arm64) target=macos-arm64 ;;
    x86_64) target=macos-x86_64 ;;
    *) echo 'Unsupported macOS architecture.' >&2; exit 2 ;;
esac
[ -f "$manifest" ] && [ -d "$artifact_root" ] || { echo 'Input path is missing.' >&2; exit 2; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
mkdir -p "$project_root/build/endpoint-packages" "$output_dir"
build_root=$(mktemp -d "$project_root/build/endpoint-packages/macos-$version.XXXXXXXX")
verified=$build_root/verified
scanner_dist=$build_root/scanner-dist
scanner_work=$build_root/scanner-work
payload=$build_root/payload
scripts=$build_root/scripts
package_file=$output_dir/endpoint-scanner-$version-$target.pkg
[ ! -e "$package_file" ] || { echo 'Refusing to overwrite an existing package.' >&2; exit 2; }

"$python" "$project_root/packaging/endpoint/tools/verify_inputs.py" \
    --manifest "$manifest" --manifest-sha256 "$manifest_sha256" \
    --artifact-root "$artifact_root" --stage-dir "$verified" \
    --target "$target" --require-component osquery
"$python" -m PyInstaller --noconfirm --clean \
    --distpath "$scanner_dist" --workpath "$scanner_work" \
    "$project_root/packaging/endpoint/endpoint-scanner.spec"

base="$payload/Library/Application Support/EndpointScanner"
install -d -m 0755 "$base/bin" "$base/tools/osquery" "$base/libexec" "$base/licenses" \
    "$base/share" "$base/state" "$payload/Library/LaunchDaemons" \
    "$payload/Library/Logs/EndpointScanner" "$payload/usr/local/sbin" "$scripts"
install -m 0755 "$scanner_dist/endpoint-scanner" "$base/bin/endpoint-scanner"
install -m 0755 "$verified/components/osquery/osqueryi" "$base/tools/osquery/osqueryi"
install -m 0755 "$script_dir/enroll-worker" "$base/libexec/enroll-worker"
install -m 0755 "$script_dir/enroll-and-start" \
    "$payload/usr/local/sbin/endpoint-scanner-enroll"
install -m 0644 "$script_dir/com.enterprise.endpoint-scanner.plist" \
    "$payload/Library/LaunchDaemons/com.enterprise.endpoint-scanner.plist"
install -m 0644 "$project_root/packaging/endpoint/config/macos.yaml" \
    "$base/share/config.yaml.dist"
install -m 0644 "$project_root/app/policies/defaults/enterprise-default.yaml" \
    "$base/share/enterprise-default.yaml.dist"
cp -R "$verified/licenses/." "$base/licenses/"
install -m 0644 "$verified/verified-inputs.json" "$base/verified-inputs.json"
install -m 0755 "$script_dir/postinstall" "$scripts/postinstall"
"$python" "$project_root/packaging/endpoint/tools/write_content_manifest.py" \
    --root "$payload" --output "$base/PACKAGE-CONTENTS.sha256"
plutil -lint "$payload/Library/LaunchDaemons/com.enterprise.endpoint-scanner.plist"
find "$payload" "$scripts" -print0 | xargs -0 touch -h -t \
    "$(date -r "$source_date_epoch" -u '+%Y%m%d%H%M.%S')"

pkgbuild --root "$payload" --scripts "$scripts" --install-location / \
    --identifier com.enterprise.endpoint-scanner --version "$version" "$package_file"
shasum -a 256 "$package_file" > "$package_file.sha256"
printf '{"status":"BUILT_UNSIGNED","package":"%s","build_root":"%s"}\n' \
    "$package_file" "$build_root"
