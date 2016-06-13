#!/bin/bash

set -ue

AMOSHASH=`git log -n 1 --pretty=format:%H`
AMOSTAG=`git tag --list --points-at $AMOSHASH`
COMMITMSG=`git log -n 1 --pretty=format:%s --grep \[TDEPLOY\]`

if [[ $AMOSTAG == *"release"* ]]
then
    if [[ $AMOSTAG == *"candidate"* ]]
    then
        echo 'release candidate';
    else
        echo 'release';
    fi
else
    if [[ $COMMITMSG == *"TDEPLOY"* ]]
    then
        echo 'test release'
    else
        echo 'no release';
    fi
        
fi



