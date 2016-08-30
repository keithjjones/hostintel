# Contributing

Fork, edit, and send me a merge request to the "devel" branch.

Modules are stored in the "libs" directory.  Each module for a new intelligence source
requires two functions:

```
add_headers(self,inputheaders)
```

and

```
add_rows(self,host,inputrow)
```

The first function will add the headers associated with the particular
module to the list of overall headers output by hostintel given by
"inputheaders".  The second function will perform the lookup and add
the data to the row "inputrow".  "inputrow" is then output by the main
script in CSV format. See the existing modules for examples.

An example skeleton module has been added to the "libs" directory for you.

After adding your module, you can add the functionality to the overall "hostintel.py"
script with the appropriate logic for your intelligence resource.