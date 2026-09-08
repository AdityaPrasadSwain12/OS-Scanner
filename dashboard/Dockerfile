FROM nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8

COPY dashboard/nginx.conf /etc/nginx/nginx.conf
COPY --chown=101:101 dashboard/index.html dashboard/app.js dashboard/styles.css /usr/share/nginx/html/

USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=4 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/dashboard-healthz"]
