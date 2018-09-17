#!/bin/bash
set -e

MY_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SAWDUST_SCRIPT=$MY_DIR/../sawdust
ls $SAWDUST_SCRIPT > /dev/null

SAWDUST_CFG=$MY_DIR/../sawdust.cfg
ls $SAWDUST_CFG > /dev/null

PERM_SCRIPT=$MY_DIR/../permission_processor
ls $PERM_SCRIPT > /dev/null

ID_SEARCH_SCRIPT=$MY_DIR/../id_search.py
ls $ID_SEARCH_SCRIPT > /dev/null
