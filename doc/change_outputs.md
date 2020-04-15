# Overview #

As of mwc-wallet 3.1.7, we add support for two new parameters which can be used via CLI or Owner API:

```
-r, --minimum_confirmations_change_outputs <minimum_confirmations_change_outputs>
            minimum confirmations required for change outputs. This value may only be set if the -exclude_change_outputs
            flag is set. [default: 1]
            
and

-x, --exclude_change_outputs    If this flag is set, 'minimum_confirmations' will not apply to change outputs for
                                    this request. Instead, minimum_confirmations_change_outputs will be used as the
                                    minimum_confirmations required for change_outputs.
```

Change outputs are defined as outputs that the wallet received from it's own send transaction.

# Problem Statement #

Some exchanges are having problems with outputs being unavailable for excessive amounts of time. This is causing
delays in withdrawals and other problems. The reason the outputs are unavailable for a long amount of time is because the users
are specifying a --min_conf value that is high. This is to prevent double spend attacks. For incoming deposits,
this --min_conf is needed (sometimes as high as 5,000) so that double spends can be detected before deposits are credited, but
it is not needed for change outputs.

# Solution #

In mwc-wallet 3.1.7, we address this problem by introducing two new parameters, which are described above. These parameters
allow the exchange to set a different number of confirmations for change outputs (default is 1) than in bound deposits. Since
change outputs are being sent by the exchange itself, there is no risk to a double spend so a much lower value may be used.

# Examples #

## CLI ##

This command will send 10 MWC, but only select from outputs that have at least 5,100 confirmations or change outputs that have
1 confirmation (1 is the default value for --minimum_confirmations_change_outputs).

```mwc-wallet send -x -c 5100 -m file -d tx.tx 10```

This command does the same, except sets the minimum confirmation for change outputs to 20.

```mwc-wallet send -x -r 20 -c 5100 -m file -d tx.tx 10```

## Owner API ##

These parameters can also be used in the owner API. Here is an example curl command that specifies both
'exclude_change_outputs' and 'minimum_confirmations_change_outputs'.

```curl -u mwc:api_secret --request POST --data-raw '{"jsonrpc":"2.0","method":"init_send_tx","params":{"args":{"src_acct_name":null,"amount":10000000000000, "minimum_confirmations":1,"max_outputs":500,"num_change_outputs":1,"selection_strategy_is_use_all":false,"message":"Take money!","target_slate_version":null,"estimate_only":null,"send_args":{"method":"http","dest":"http://10.0.0.243:3415","finalize":true,"post_tx":true,"fluff":false},"exclude_change_outputs":true, "minimum_confirmations_change_outputs": 200,"payment_proof_recipient_address":null,"ttl_blocks":1000}},"id":1}' http://127.0.0.1:3420/v2/owner```
