#!/usr/bin/env bash
. /Users/Evanv0/go/src/github.com/dedis/cothority/app/lib/test/cothorityd.sh
. /Users/Evanv0/go/src/github.com/dedis/cothority/app/lib/test/libtest.sh
STATICDIRt=/Users/Evanv0/go/src/github.com/dedis/cothority/app/test
runCl(){
    D=cl$1/group.toml
    shift
    dbgRun /Users/Evanv0/cothority/app/guardopenldap/guard -d 0 $@
}

build(){
    BUILDDIR=/Users/Evanv0/go/src/github.com/dedis/cothority/app
    if [ "$STATICDIRt" ]; then
        DIRt=$STATICDIRt
    else
        DIRt=$(mktemp -d)
    fi
    mkdir -p $DIRt
    cd $DIRt
    testOut "Building in $DIRt"
    for app in $BUILDDIR/guard $BUILDDIR/cothorityd; do
        if [ ! -e $app -o "$BUILD" ]; then
            go build -o $app $BUILDDIR/$app/*go
        fi
    done
    for n in $(seq $NBR); do
        srv=srv$n
        rm -rf $srv
        mkdir $BUILDDIR/test/$srv
        cl=$BUILDDIR/test/cl$n
        rm -rf $cl
        mkdir $cl
    done
}
main () {
	stopTest
	build
	mkdir -p $TESTDIR $DBDIR1
	cothoritySetup
	cp group.toml cl1
	runCl 1 su cl1/group.toml
}
main