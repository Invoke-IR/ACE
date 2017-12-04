FROM microsoft/mssql-server-linux
MAINTAINER Jared Atkinson <jared@invoke-ir.com>

ENV ACCEPT_EULA Y

# Create app directory
RUN mkdir -p /usr/src/ace
WORKDIR /usr/src/ace

# Copy files to container
COPY import-data.sh /usr/src/ace
COPY ace.sql /usr/src/ace

# Grant permissions for the import-data script to be executable
RUN chmod +x /usr/src/ace/import-data.sh

CMD /bin/bash /usr/src/ace/import-data.sh