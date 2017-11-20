#!/usr/bin/python
"""
Loads test datasets for the GA4GH server

Based on the arguments provided from the deployer, one of the datsets is loaded
"""

import sys
import subprocess

def loadExtra(dataReg):
    """Loads a subset of the 1000g data based on the GA4GH documentation"""
    subprocess.call(["mkdir", dataDir])
    subprocess.call(["ga4gh_repo", "init", dataReg])   
    subprocess.call(["ga4gh_repo", "add-dataset", dataReg, "1kgenomes", "--description", "Variants  from the 1000 Genomes project and GENCODE genes annotations"])
    subprocess.call(["wget", "ftp://ftp.1000genomes.ebi.ac.uk//vol1/ftp/technical/reference/phase2_reference_assembly_sequence/hs37d5.fa.gz"])
    subprocess.call(["gunzip", "hs37d5.fa.gz"])
    subprocess.call(["git", "clone", "https://github.com/samtools/htslib", ".."])
    subprocess.call(["apt-get", "install" "-y", "autoconf", "libbz2-dev", "liblzma-dev", "make"])
    subprocess.call(["autoconf"], cwd="../htslib")
    subprocess.call(["../htslib/configure"])
    subprocess.call(["make"], cwd="../htslib")
    subprocess.call(["../htslib/bgzip", "hs37d5.fa"])
    subprocess.call(["ga4gh_repo", "add-referenceset", dataReg, "hs37d5.fa.gz", "-d", "NCBI37 assembly of the human genome", "--name", "NCBI37", "--sourceUri", "ftp://ftp.1000genomes.ebi.ac.uk/vol1/ftp/technical/reference/phase2_reference_assembly_sequence/hs37d5.fa.gz"])
    subprocess.call(["wget", "https://raw.githubusercontent.com/The-Sequence-Ontology/SO-Ontologies/master/so-xp-dec.obo"]) 
    subprocess.call(["ga4gh_repo", "add-ontology", dataReg, "so-xp-dec.obo", "-n", "so-xp"])
    subprocess.call(["wget", "-m", "ftp://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502/", "-nd", "-P", "release", "-l", "1"])
    os.remove("./release/ALL.wgs.phase3_shapeit2_mvncall_integrated_v5b.20130502.sites.vcf.gz")
    os.remove("./release/ALL.wgs.phase3_shapeit2_mvncall_integrated_v5b.20130502.sites.vcf.gz.tbi")
    subprocess.call(["ga4gh_repo", "add-variantset", dataReg, "1kgenomes", "release/", "--name", "phase3-release", "--referenceSetName", "NCBI37"])
    subprocess.call(["wget", "http://s3.amazonaws.com/1000genomes/phase3/data/HG00096/alignment/HG00096.mapped.ILLUMINA.bwa.GBR.low_coverage.20120522.bam.bai"])
    subprocess.call(["ga4gh_repo", "add-readgroupset", dataReg, "1kgenomes", "-I", "HG00096.mapped.ILLUMINA.bwa.GBR.low_coverage.20120522.bam.bai", "--referenceSetName", "NCBI37", "http://s3.amazonaws.com/1000genomes/phase3/data/HG00096/alignment/HG00096.mapped.ILLUMINA.bwa.GBR.low_coverage.20120522.bam"])


dataArg = sys.argv[1]

dataDir = "/srv/ga4gh-compliance-data"
dataReg = dataDir + "/registry.db"

if dataArg == "default":
    # load a minimal test set
    subprocess.call(["python", "/srv/ga4gh-server/scripts/prepare_compliance_data.py", "-o", dataDir])
elif dataArg == "extra":
    # load many gigabytes of data from the 1000g dataset
    # this operation takes many hours 
    loadExtra(dataReg)
else:
    # load no data
    subprocess.call(["mkdir", dataDir])
    subprocess.call(["ga4gh_repo", "init", dataReg])
exit
