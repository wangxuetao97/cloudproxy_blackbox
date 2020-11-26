#!/bin/bash

# set -e

image_prefix="cp_blackbox_"
proj_dir=$(git rev-parse --show-toplevel)

function ls_dk_img {
    echo -n "$(docker images --format '{{.Repository}}:{{.Tag}}:{{.ID}}')"
}

# $1 is role
# return in stdout
function make_dk_tag {
    local role="$1"
    local today=$(date '+%Y%m%d')
    local today_imgs=$(ls_dk_img | grep "${image_prefix}${role}" | grep "$today")
    if [ -z "$today_imgs" ]; then
        echo -n "$today"
    else
        local cnt=$(echo "$today_imgs" | wc -l)
        echo -n "$today-$cnt"
    fi
}

# return in stdout
function make_git_tag {
    local today=$(date '+%Y%m%d')
    local cnt=$(git tag --list | grep "$today" | wc -l)
    if [ "$cnt" -eq 0 ]; then
        echo -n "$today"
    else
        echo -n "$today-$cnt"
    fi
}

# $1 is tag name
# return void
function add_git_tag {
    git tag -a "$1" -m cloudproxy_blackbox
}

# return tags in stdout
function check_git_tag {
    # set +e
    echo -n $(git describe --tags --exact-match 2> /dev/null)
    # set -e
}

function tag_project {
    local tag=$(check_git_tag)
    [ -n "$tag" ] && echo "$proj_dir has been tagged." && return 1
    local new_tag=$(make_git_tag)
    add_git_tag "$new_tag"
    echo "tag project success, new tag: $new_tag"
}

# $1 is role
function build_role {
    local role="$1"
    [ -z "$role" ] && echo "\$1 should be role name." && return 1
    local dkroletag=$(make_dk_tag "$role")
    local dkrolename="${image_prefix}${role}:${dkroletag}"
    docker build -f "$proj_dir/image/cp_blackbox_${role}.dkf" -t "$dkrolename" "$proj_dir"
}

function build_project {
    local gittag=$(check_git_tag)
    [ -z "$gittag" ] && echo "repo needs to be tagged" && return 1
    echo "building docker image..."
    build_role tcp
    build_role udp
    build_role tls
    echo "build image success"
}

if [ "$1" = "-t" ]; then
    tag_project
elif [ "$1" = "-b" ]; then
    build_project
else
    echo "do nothing, quit now"
    exit 1
fi


