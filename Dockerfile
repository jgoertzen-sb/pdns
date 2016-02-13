FROM debian:jessie

RUN apt-get update && apt-get install -y \
    autoconf\
    automake\
    bison\
    flex\
    g++\
    git\
    libboost-all-dev\
    libtool\
    make\
    pkg-config\
    ragel\
    libmysqlclient-dev\
    libssl-dev\
    build-essential\
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
 
RUN useradd pdns

RUN mkdir -p /usr/src/pdns
WORKDIR /usr/src/pdns

COPY . /usr/src/pdns/

RUN ./bootstrap
RUN ./configure --with-modules="gmysql" --without-lua
RUN make -j5
RUN make install

COPY ./pdns-mysql.conf /etc/powerdns/pdns.d/pdns.local.gmysql.conf
COPY ./pdns.conf /etc/powerdns/pdns.conf
 
CMD ["pdns_server","--daemon=no","--config-dir=/etc/powerdns/"]

