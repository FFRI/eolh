#
# (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
#
if [ ! -d ./golang-etw ]; then
    git clone https://github.com/0xrawsec/golang-etw.git
    cp diff.patch golang-etw/
    cd golang-etw
    git checkout 4b60579
    patch -p1 < diff.patch
fi
