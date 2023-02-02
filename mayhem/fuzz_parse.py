#! /usr/bin/env python3
import atheris
import sys

with atheris.instrument_imports():
    from libnmap.parser import NmapParser, NmapParserException
    from libnmap.objects.report import NmapReport


def load_nmap_report(fdp: atheris.FuzzedDataProvider) -> NmapReport:
    nmap_data = fdp.ConsumeString(fdp.ConsumeIntInRange(0, fdp.remaining_bytes()))
    return NmapParser.parse_fromstring(nmap_data)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        rep1, rep2 = load_nmap_report(fdp), load_nmap_report(fdp)
        if not rep1 or not rep2:
            return -1
        rep1.diff(rep2).changed()
        rep1.diff(rep2).unchanged()
    except NmapParserException:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
