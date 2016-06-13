#!/bin/bash

###
# Copyright 2017 The Open Source Research Group,
#                University of Erlangen-Nürnberg
#
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.gnu.org/licenses/gpl.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -ue

AMOSHASH=`git log -n 1 --pretty=format:%H`
AMOSTAG=`git tag --list --points-at $AMOSHASH`
COMMITMSG=`git log -n 1 --pretty=format:%s --grep \[TDEPLOY\]`

if [[ $AMOSTAG == *"release"* ]]
then
    if [[ $AMOSTAG == *"candidate"* ]]
    then
        echo 'deploying test--candidate';
        bash deploy/testdeploy.sh
    else
        echo 'deploying realease--candidate';
        bash deploy/releasedeploy.sh
    fi
else
    if [[ $COMMITMSG == *"TDEPLOY"* ]]
    then
        echo 'deploying test--candidate';
        bash deploy/testdeploy.sh
    else
        echo 'not deploying anything';
    fi
        
fi



