# DMARC report analyzer

Check quickly DMARC reports in XML format if they contain any DMARC errors. If a report contain errors, the further error analysis is necessary which is not in the scope of this tool.

# How to install

### Dependencies:

This tool is written in D language. To build, D compiler (dmd) and packaging tool (dub) are needed. Other build dependencies will be handled by the packaging tool.

### To build:

In the folder where the cloned git repository is run:

```
dub build
```

This will fetch all build dependencies and build the executable.

### To run:

Extract DMARC reports to analyse into a folder. DMARC reports are expected to be in XML format. To check the reports, run:

```
path/to/dmarc-report-analyzer path/to/dmarc/reports
```

# Validation conditions

This tool considers DMARC reports 'valid' if:


For each *row* in a *record*:
* *disposition* value in *policy_evaluated* is 'none'
* *dkim* value in *policy_evaluated* is 'pass'
* *spf* value in *policy_evaluated* is 'pass'


For *auth_results* in a *record*:
* *result* value for *spf* is 'pass'
* *result* value for *dkim* is 'pass'

