FROM postgres:12
RUN echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
RUN printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
RUN apt-get update && apt-get install -y sudo iputils-ping iproute2 jq vim netcat default-libmysqlclient-dev libsqlite3-dev postgresql-client-11 postgresql-server-dev-11 libpq-dev python3-pip bridge-utils wireguard linux-source curl git libssl-dev pkg-config build-essential ipset python3-setuptools python3-wheel dh-autoreconf procps
RUN apt-get install -y -t unstable iperf3
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV POSTGRES_USER=postgres
ENV POSTGRES_BIN=/usr/lib/postgresql/12/bin/postgres
ENV INITDB_BIN=/usr/lib/postgresql/12/bin/initdb
ARG SPEEDTEST_THROUGHPUT
ARG SPEEDTEST_DURATION
ARG VERBOSE
ARG NODES
ENV SPEEDTEST_THROUGHPUT=$SPEEDTEST_THROUGHPUT
ENV SPEEDTEST_DURATION=$SPEEDTEST_DURATION
ENV VERBOSE=$VERBOSE
RUN PATH=$PATH:$HOME/.cargo/bin cargo install diesel_cli --force
ENV NODES=$NODES
# we pull in the git tar instead of the local folder becuase the raw code is much much smaller
# note that changes have to be checked in to be pulled in and tested! we pull this in near
# the bottom to maximize caching of earlier containers
ADD rita.tar.gz /
CMD PATH=$PATH:$HOME/.cargo/bin INITIAL_POLL_INTERVAL=5 BACKOFF_FACTOR="1.5" /althea_rs/integration-tests/rita.sh
