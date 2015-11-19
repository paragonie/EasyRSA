#!/usr/bin/env bash

php vendor/bin/phpunit test
if [ $? -ne 0 ]; then
    # Test failure
    exit 1
fi
