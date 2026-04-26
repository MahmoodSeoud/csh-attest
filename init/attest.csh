# csh-attest boot script.
#
# Loads the csh-attest APM into csh. Use as:
#   csh -i init/attest.csh
#
# In session 1 the APM only registers a `hello` placeholder command. The full
# attest / attest-diff command surface lands in session 2 once the
# introspection adapters and JCS canonicalization are wired.
apm load -p ./build
