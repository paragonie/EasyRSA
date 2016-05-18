#!/usr/bin/env bash

vendor/bin/phpunit test
if [ $? -ne 0 ]; then
    # Test failure
    exit 1
fi
