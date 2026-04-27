# csh-attest boot script.
#
# Loads the csh-attest APM into csh. Use as:
#   csh -i init/attest.csh
#
# Registers the full command surface: `attest --emit | --sign | --verify |
# --remote` and `attest-diff`. Run `help attest` once you're at the csh
# prompt for the inline usage line.
apm load -p ./build
