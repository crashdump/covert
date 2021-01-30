# Approach

Coverts encrypted volumes are composed of one or more of the following parts concatenated together.

- Secret partition (SP): Secret file(s) we want to protect.
- Decoy partition (DP): Innocuous file(s), as decoys.
- Garbage Partition (RP): Key is thrown away during volume creation.

Decoy and secret partitions are optional, you can use this tool to create a single AES-256 partition.

You could, for example, create a new volume composed of 5 parts:

| _DP_ | *SP* | GP | _DP_ | GP |

If you were put in a position where you were forced to give away the keys, you could provide one, or two, of the
insignificant partitions. Keeping to Secret partition's key to yourself and pretending you do not have the key to
the other volumes, as they are garbage.

## Considerations

- The minimum number of partitions is 3: 1 SP, 1 IP and 1 RP, there are no maximums.
- All the partitions are always of the same size, and a total volume size is always `vsize = biggest_file * number_partition`.
- Partition location are random.
- Covert only supports 1 file per partition currently.
- The performance of the implementation could be optimised in a few areas.

## Flows

When a user enters a key, Covert will iterate over all the partitions until it find one for which the key matches. If
no matching partition are found the decryption will fail.

## Choice of algorithms