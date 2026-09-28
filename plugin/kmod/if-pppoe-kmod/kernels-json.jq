# kernels-json-file (Makefile): KERNELS_JSON entries of the staged build_ids
# ($ids = the build_ids file); every staged build_id must have one.
($ids | split("\n") | map(select(length > 0))) as $b
| [.[] | select(.build_id | IN($b[]))]
| if (map(.build_id) | sort) == ($b | sort) then .
  else error("staged build_ids without a KERNELS_JSON entry: \($b - map(.build_id))") end
