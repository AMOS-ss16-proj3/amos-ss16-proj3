#
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



FROM osrgroup/amos-downloader-base-image:1.0

#ENV DOIP_V1 doip_v1.so
#ENV DOIP_V2 doip_v2.so

ADD ./index.html /var/www/html/index.html

ADD ./plugins/doip_v1.so /var/www/html/doip_v1.so
ADD ./plugins/doip_v2.so /var/www/html/doip_v2.so
#ADD ./insert_plugins.sh /assets/insert_plugins.sh
#ADD ./insert-win-link.sh /assets/insert-win-link.sh
#RUN bash /assets/insert_plugins.sh
#RUN bash /assets/insert-win-link.sh
