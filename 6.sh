#!/bin/bash

dig challenge.i18.no txt | grep -oE "answer=[0-9a-fA-F]+" | grep -oE "[0-9a-fA-F]+$"
