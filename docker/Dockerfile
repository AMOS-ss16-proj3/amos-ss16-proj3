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

ENV HTML_INDEX_FILE doip.so

ADD ./plugins/$HTML_INDEX_FILE /var/www/html/$HTML_INDEX_FILE
ADD ./insert-win-link.sh /assets
RUN bash /assets/insert-windows-link.sh
