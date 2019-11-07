How to use this gist
--------------------

You have two options:

1. Read all the comments and source code
2. Run stuff without knowing what it does

```
python extract_private_key_from_hsm_secret.py
```

This will print your node's private key. Take it and pass it to the next command:

```
python generate_custom_invoice_with_lnurl.py <privatekey>
```

This will print data for the custom invoice.

Please let me know if you didn't understand something or if anything is broken.

---

This gist uses slightly modified code from https://github.com/rustyrussell/lightning-payencode. Hopefully Rusty won't sue me.
