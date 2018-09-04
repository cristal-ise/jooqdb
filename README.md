# CRISTAL-iSE JOOQDB[![Build Status](https://travis-ci.org/cristal-ise/jooqdb.svg?branch=master)](https://travis-ci.org/cristal-ise/jooqdb)
Implementation of CRISTAL-iSE ClusterStorage and Lookup interfaces based on http://jooq.org


## JOOQDB specific CRISTAL configuration properties

`JOOQ.TemporaryPwdFieldImplemented = false` disables the use of TempraryPassword, must be used for databases which did not updated the ITEM table
