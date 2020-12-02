#!/bin/bash

proj_dir=$(git rev-parse --show-toplevel)

function build {
    "$proj_dir"/image/build_image.sh -t
    "$proj_dir"/image/build_image.sh -b
}

# $1 is role
function get_image_name {
    local role="$1"
    echo $(docker images --format {{.Repository}}:{{.Tag}} | grep cp_blackbox_"$role" | sort | tail -n 1)
}

function start {
    # use media_server_cloud_proxy test env docker network
    docker run -d --rm --network test_env_network_proxy $(get_image_name tcp)
    docker run -d --rm --network test_env_network_proxy $(get_image_name udp)
    docker run -d --rm --network test_env_network_proxy $(get_image_name tls)
}

if [[ $# -eq 0 ]]; then
    build
    start
elif [[ $1 == -b ]]; then
    build
elif [[ $1 == -s ]]; then
    start
fi
