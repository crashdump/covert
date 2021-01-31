# Approach

Coverts encrypted volumes are composed of one or more of the following parts concatenated together.

- Secret partition (SP): Secret file(s) we want to protect.
- Decoy partition (DP): Innocuous file(s), as decoys.
- Garbage Partition (RP): Key is thrown away during volume creation.

Note: Decoy and secret partitions are optional, but you should probably specify them. 
Note: A volume is composed of at least 3 partitions.

You could, for example, create a new volume composed of 3 partitions:

| _Decoy_ | *Secret* | Garbage |

If you were put in a position where you were forced to give away the keys, you could provide the key to the 
insignificant partition. Keeping the Secret partition's key to yourself and pretending you do not have the
key to the other volumes, and that they are all garbage.

You could go further by adding, for example, two or more decoy partitions.

| _Decoy_ | *Secret* | _Decoy_ | Garbage |

## Considerations

- All the partitions are always of the same size, and the volume size is `vsize = number_partition * (biggest_file + AES overhead)`.
- Partition location are randomised during the creation of the volume.
- Covert currently only supports 1 file per partition (you could provide an ISO-9660 or a DMG to work around this, though).
- The current implementation can be slow with large amounts of data

## Flows

When a user enters a key, Covert will iterate over all the partitions until it find one for which the key matches. If
no matching partition are found the decryption will fail.