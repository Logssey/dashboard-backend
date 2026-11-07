{ cluster: $cluster, namespace: $ns, observedAt: (now | todate),
  workloads: ( [ .items[] | select(.status.phase == "Running")
      | (((.metadata.ownerReferences // []) | map(select(.controller == true)) | .[0])
         // {kind: "Pod", name: .metadata.name}) as $o
      | (.metadata.labels["pod-template-hash"] // "") as $h
      | (.spec.containers | map({key: .name, value: .image}) | from_entries) as $spec
      | any(.status.conditions[]?; .type == "Ready" and .status == "True") as $ready
      | { kind: (if $o.kind == "ReplicaSet" then "Deployment" else $o.kind end),
          name: (if $o.kind == "ReplicaSet" and $h != "" then ($o.name | rtrimstr("-" + $h)) else $o.name end),
          containers: [ .status.containerStatuses[]?
                        | select((.imageID // "") | test("@sha256:[0-9a-f]{64}$"))
                        | {name, image: ($spec[.name] // .image),
                           imageDigest: (.imageID | split("@")[1]), ready: $ready} ] } ]
    | group_by([.kind, .name])
    | map({ kind: .[0].kind, name: .[0].name,
            containers: ( map(.containers[]) | group_by([.name, .imageDigest])
                          | map({ name: .[0].name, imageDigest: .[0].imageDigest,
                                  image: (map(.image) | min),
                                  readyReplicas: (map(select(.ready)) | length) }) ) }) ) }
