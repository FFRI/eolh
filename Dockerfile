#
# (c) FFRI Security, Inc., 2024 / Author: FFRI Security, Inc.
#

FROM mcr.microsoft.com/windows/nanoserver:ltsc2022

COPY eolh.exe /

ENTRYPOINT ["powershell"]
