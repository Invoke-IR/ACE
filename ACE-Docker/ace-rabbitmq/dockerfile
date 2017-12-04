FROM  rabbitmq:3-management
MAINTAINER Jared Atkinson <jared@invoke-ir.com>
ADD ace-entrypoint.sh /root/ace-entrypoint.sh
ADD ace-cache.py /root/ace-cache.py
ADD ace-lookup.py /root/ace-lookup.py
RUN \
    chmod +x /root/ace-entrypoint.sh \
    && chmod +x /root/ace-cache.py \
    && chmod +x /root/ace-lookup.py \
    && apt-get update -y \
    && apt-get upgrade -y \
    && apt-get dist-upgrade -y \
    && apt-get install -y python2.7 python-pip \
    && pip install pika requests
CMD \
    /usr/local/bin/docker-entrypoint.sh rabbitmq-server > /dev/null & \
    sleep 30 \
    && /root/ace-entrypoint.sh