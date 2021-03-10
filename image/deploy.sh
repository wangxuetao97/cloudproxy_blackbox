#!/bin/bash

function git_user {
    local email=$(git config -l | grep ^user.email)
    if [[ -z $email ]]; then
        git config user.email wangxuetao@agora.io
        git config user.name "Wang Xuetao"
    fi
}

function build {
    git_user
    local proj_dir=$(git rev-parse --show-toplevel)
    "$proj_dir"/image/build_image.sh -t
    "$proj_dir"/image/build_image.sh -b
}

# $1 is role
function get_image_name {
    local role="$1"
    echo $(docker images --format {{.Repository}}:{{.Tag}} | grep cp_blackbox_"$role" | sort | tail -n 1)
}

function start {
    docker run -d --network host --restart unless-stopped -v /data/log/agora:/data/log/agora --name cpblx_tcp $(get_image_name tcp)
    docker run -d --network host --restart unless-stopped -v /data/log/agora:/data/log/agora --name cpblx_udp $(get_image_name udp)
    docker run -d --network host --restart unless-stopped -v /data/log/agora:/data/log/agora --name cpblx_tls $(get_image_name tls)
}

function stop {
    cons=$(docker ps --format {{.ID}}:{{.Image}} | grep cp_blackbox_ | cut -f1 -d:)
    if [[ -n "$cons" ]]; then
        echo "$cons" | xargs docker stop
    fi
}

function remove {
    cons=$(docker ps -a --format {{.ID}}:{{.Image}} | grep cp_blackbox_ | cut -f1 -d:)
    if [[ -n "$cons" ]]; then
        echo "$cons" | xargs docker rm
    fi
}

function rmlog {
    echo '' | sudo tee '/data/log/agora/cloudproxy_blackbox_tcp.log'
    echo '' | sudo tee '/data/log/agora/cloudproxy_blackbox_tls.log'
    echo '' | sudo tee '/data/log/agora/cloudproxy_blackbox_udp.log'
}

if [[ $# -eq 0 ]]; then
    build
    stop
    remove
    start
elif [[ $1 == build ]]; then
    build
elif [[ $1 == start ]]; then
    start
elif [[ $1 == git ]]; then
    git_user
elif [[ $1 == stop ]]; then
    stop
elif [[ $1 == remove ]]; then
    remove
elif [[ $1 == rmlog ]]; then
    rmlog
else
    echo "Nothing to do, exit now."
fi
