#!/usr/bin/env python3
from pathlib import Path
import sys

import pbk


def main():
    #log = pbk.LoggingConnection()
    datadir = Path.home() / ".bitcoin"
    print("Loading chain manager... ", end='', flush=True)
    chainman = pbk.load_chainman(datadir, pbk.ChainType.MAINNET)
    print("done.")

    # TODO: read blocks here
    tip = chainman.get_block_index_from_tip()
    print(f"Current block tip: {tip.block_hash.hex} at height {tip.height}")


if __name__ == "__main__":
    main()
