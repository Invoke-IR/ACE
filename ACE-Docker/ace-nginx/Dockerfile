FROM nginx
MAINTAINER Jared Atkinson <jared@invoke-ir.com>
RUN apt-get update; apt-get install -y openssl
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh
CMD /bin/bash /opt/entrypoint.sh && nginx -c /etc/nginx/nginx.conf -g "daemon off;"