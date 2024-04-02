#
# (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
#

git clone https://github.com/0xrawsec/golang-etw.git
cd golang-etw
patch -p1 < diff.patch
cd ..
docker buildx build --platform windows/amd64 --output=type=registry --pull -f Dockerfile -t $repository/monitor:$tag .
