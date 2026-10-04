#!/bin/bash
set -euo pipefail

# These refs must be owner-created and immutable in repository tag rulesets.
test "$ACTOR" = patryk-roguszewski
test "$EVENT_NAME" = workflow_dispatch
test "$REF_TYPE" = tag
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$MARKETING_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
test "$SOURCE_SHA" = "$TAG_SHA"
if [[ "$RELEASE_PIPELINE" == true ]]; then
  if [[ "$MARKETING_VERSION" = 0.0.1 && "$REF_NAME" =~ ^v0[.]0[.]1[+]retry[.][1-9][0-9]*$ ]]; then
    : # Failed immutable first-release tags cannot be moved to a repaired source.
  else
    test "$REF_NAME" = "v$MARKETING_VERSION"
  fi
else
  test "$REF_NAME" = "signing-$MARKETING_VERSION-$SOURCE_SHA"
fi
