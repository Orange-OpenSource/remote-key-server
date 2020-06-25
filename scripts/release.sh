#!/bin/sh

OLD_VERSION=${1:?}
VERSION=${2:?}

git tag "$VERSION"
sed -i -E "s/${OLD_VERSION}/${VERSION}/" ./pkg/model/constantes.go
