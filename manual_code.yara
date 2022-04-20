rule manual_code{
    meta:
        author = " Newton "
        Description = " First Yara Project"
        hash = ""

    strings:
        $a = "secretstorage"
        $b = "https://github.com/skelsec/pypykatz/archive/master.zip"
    
    condition:
        ( $a or $b )
}