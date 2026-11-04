{ cluster: $cluster, namespace: $ns, observedAt: (now | todate),
  workloads: ( [ .items[] | select(.status.phase == "Running")
      | (((.metadata.ownerReferences // []) | map(select(.controller == true)) | .[0])
         // {kind: "Pod", name: .metadata.name}) as $o
      | (.metadata.labels["pod-template-hash"] // "") as $h
      | { kind: (if $o.kind == "ReplicaSet" then "Deployment" else $o.kind end),
          name: (if $o.kind == "ReplicaSet" and $h != "" then ($o.name | rtrimstr("-" + $h)) else $o.name end),
          ready: any(.status.conditions[]?; .type == "Ready" and .status == "True"),
          containers: [ .status.containerStatuses[]?
                        | select((.imageID // "") | test("@sha256:[0-9a-f]{64}$"))
                        | {name, image, imageDigest: (.imageID | split("@")[1])} ] } ]
    | group_by([.kind, .name])
    | map({ kind: .[0].kind, name: .[0].name,
            readyReplicas: (map(select(.ready)) | length),
            containers: (map(.containers[]) | unique) }) ) }
