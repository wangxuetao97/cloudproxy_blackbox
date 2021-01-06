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
    docker run -d --rm --network host --name cpblx_tcp $(get_image_name tcp)
    docker run -d --rm --network host --name cpblx_udp $(get_image_name udp)
    docker run -d --rm --network host --name cpblx_tls $(get_image_name tls)
}

if [[ $# -eq 0 ]]; then
    build
    start
elif [[ $1 == -b ]]; then
    build
elif [[ $1 == -s ]]; then
    start
elif [[ $1 == -g ]]; then
    git_user
fi
