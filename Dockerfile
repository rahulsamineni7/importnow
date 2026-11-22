# Multi-stage hardened unprivileged Nginx image
FROM nginx:alpine-slim

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy website assets
COPY . /usr/share/nginx/html/

# Copy hardened nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Clean up build artifacts if any
RUN rm -rf /usr/share/nginx/html/Dockerfile \
           /usr/share/nginx/html/docker-compose.yml \
           /usr/share/nginx/html/nginx.conf \
           /usr/share/nginx/html/*.py \
           /usr/share/nginx/html/scripts

# Set security file permissions
RUN chmod -R 755 /usr/share/nginx/html

# Expose HTTP port
EXPOSE 80

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
