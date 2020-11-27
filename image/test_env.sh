#!/bin/bash

./build_image.sh -t
./build_image.sh -b

# $1 is role
function get_image_name {
    local role="$1"
    echo $(docker images --format {{.Repository}}:{{.Tag}} | grep cp_blackbox_"$role" | sort | tail -n 1)
}

# use media_server_cloud_proxy test env docker network
docker run -d --rm --network test_env_network_proxy $(get_image_name tcp)
docker run -d --rm --network test_env_network_proxy $(get_image_name udp)
docker run -d --rm --network test_env_network_proxy $(get_image_name tls)
