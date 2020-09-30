#!/bin/bash
set -eux
NODES=${NODES:='None'}

RUST_TEST_THREADS=1 cargo test --all

if ! modprobe wireguard ; then
	echo "The container can't load modules into the host kernel"
	echo "Please install WireGuard https://www.wireguard.com/ and load the kernel module using 'sudo modprobe wireguard'"
	exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKERFOLDER=$DIR/../integration-tests/container/
REPOFOLDER=$DIR/..
git archive --format=tar.gz -o $DOCKERFOLDER/rita.tar.gz --prefix=althea_rs/ HEAD
pushd $DOCKERFOLDER
time docker build -t rita-test --build-arg NODES=$NODES --build-arg SPEEDTEST_THROUGHPUT="20" --build-arg SPEEDTEST_DURATION="15" --build-arg INITIAL_POLL_INTERVAL=5 --build-arg BACKOFF_FACTOR="1.5" --build-arg VERBOSE=1 .
time docker run --privileged -t rita-test
rm rita.tar.gz
popd
