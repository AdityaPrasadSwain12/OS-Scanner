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
[ "$(uname -s)" = Linux ] || { echo 'Build the Debian package on Linux.' >&2; exit 2; }
case "$(dpkg --print-architecture)" in
    amd64) architecture=amd64; target=linux-x86_64 ;;
    arm64) architecture=arm64; target=linux-arm64 ;;
    *) echo 'This scaffold supports Debian amd64 and arm64.' >&2; exit 2 ;;
esac
[ -f "$manifest" ] && [ -d "$artifact_root" ] || { echo 'Input path is missing.' >&2; exit 2; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
mkdir -p "$project_root/build/endpoint-packages" "$output_dir"
build_root=$(mktemp -d "$project_root/build/endpoint-packages/linux-$version.XXXXXXXX")
verified=$build_root/verified
scanner_dist=$build_root/scanner-dist
scanner_work=$build_root/scanner-work
package_root=$build_root/package-root
package_file=$output_dir/endpoint-scanner_${version}_${architecture}.deb
[ ! -e "$package_file" ] || { echo 'Refusing to overwrite an existing package.' >&2; exit 2; }

"$python" "$project_root/packaging/endpoint/tools/verify_inputs.py" \
    --manifest "$manifest" --manifest-sha256 "$manifest_sha256" \
    --artifact-root "$artifact_root" --stage-dir "$verified" \
    --target "$target" --require-component osquery
"$python" -m PyInstaller --noconfirm --clean \
    --distpath "$scanner_dist" --workpath "$scanner_work" \
    "$project_root/packaging/endpoint/endpoint-scanner.spec"

install -d -m 0755 "$package_root/DEBIAN" "$package_root/opt/endpoint-scanner/bin" \
    "$package_root/opt/endpoint-scanner/tools/osquery" \
    "$package_root/opt/endpoint-scanner/libexec" \
    "$package_root/opt/endpoint-scanner/licenses" \
    "$package_root/etc/endpoint-scanner/policies" "$package_root/lib/systemd/system" \
    "$package_root/usr/sbin" "$package_root/usr/share/doc/endpoint-security-scanner"
install -m 0755 "$scanner_dist/endpoint-scanner" \
    "$package_root/opt/endpoint-scanner/bin/endpoint-scanner"
install -m 0755 "$verified/components/osquery/osqueryi" \
    "$package_root/opt/endpoint-scanner/tools/osquery/osqueryi"
install -m 0755 "$script_dir/enroll-worker" \
    "$package_root/opt/endpoint-scanner/libexec/enroll-worker"
install -m 0755 "$script_dir/enroll-and-start" \
    "$package_root/usr/sbin/endpoint-scanner-enroll"
install -m 0644 "$script_dir/endpoint-scanner.service" \
    "$package_root/lib/systemd/system/endpoint-scanner.service"
install -m 0640 "$project_root/packaging/endpoint/config/linux.yaml" \
    "$package_root/etc/endpoint-scanner/config.yaml"
install -m 0640 "$project_root/app/policies/defaults/enterprise-default.yaml" \
    "$package_root/etc/endpoint-scanner/policies/enterprise-default.yaml"
cp -R "$verified/licenses/." "$package_root/opt/endpoint-scanner/licenses/"
install -m 0644 "$verified/verified-inputs.json" \
    "$package_root/usr/share/doc/endpoint-security-scanner/verified-inputs.json"

sed -e "s/@VERSION@/$version/g" -e "s/@ARCHITECTURE@/$architecture/g" \
    "$script_dir/control.template" > "$package_root/DEBIAN/control"
for maintainer_script in postinst prerm postrm; do
    install -m 0755 "$script_dir/$maintainer_script" "$package_root/DEBIAN/$maintainer_script"
done
install -m 0644 "$script_dir/conffiles" "$package_root/DEBIAN/conffiles"

contents=$package_root/usr/share/doc/endpoint-security-scanner/PACKAGE-CONTENTS.sha256
"$python" "$project_root/packaging/endpoint/tools/write_content_manifest.py" \
    --root "$package_root" --output "$contents"
find "$package_root" -print0 | xargs -0 touch -h -d "@$source_date_epoch"
SOURCE_DATE_EPOCH=$source_date_epoch dpkg-deb --root-owner-group --build "$package_root" "$package_file"
sha256sum "$package_file" > "$package_file.sha256"
printf '{"status":"BUILT_UNSIGNED","package":"%s","build_root":"%s"}\n' \
    "$package_file" "$build_root"
