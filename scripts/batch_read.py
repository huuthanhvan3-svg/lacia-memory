#!/usr/bin/env python3
"""Batch read 10 books: extract TOC + key content for each."""
import subprocess, os, sys

BOOKS = [
    ("1. Attacking Network Protocols", 
     "/home/lacia/books/Hacking_books/attackingnetworkprotocols_ebook.pdf", 
     [1,7,9,10]),
    ("2. Hacking: The Art of Exploitation",
     "/home/lacia/books/Hacking_books/hacking_artofexploitation_2ndedition.pdf",
     [1,2,3,4]),
    ("3. The Web Application Hacker's Handbook",
     "/home/lacia/books/hacking_books_collection/The Web Application Hacker's Handbook_ Finding and Exploiting Security Flaws.pdf",
     [1,2,3,4]),
    ("4. Linux Basics for Hackers",
     "/home/lacia/books/kalyan-deva-hacking-books/Hacking-Bug-Bounty-Books-main/Linux Basics for Hackers_ Getting Started with Networking, Scripting, and Security in Kali.pdf",
     [1,2,3]),
    ("5. The Basics of Web Hacking",
     "/home/lacia/books/Hacking-books/54. The Basics of Web Hacking - Tools and Techniques to Attack the Web(2013).pdf",
     [1,2,3,4]),
    ("6. Gray Hat Python",
     "/home/lacia/books/kalyan-deva-hacking-books/Hacking-Bug-Bounty-Books-main/Gray Hat Python.pdf",
     [1,2,3,4]),
    ("7. Bug Bounty Playbook V2",
     "/home/lacia/books/hacking_books_collection/Bug-Bounty-Playbook-V2.pdf",
     [1,2,3,4,5]),
    ("8. Web Hacking 101",
     "/home/lacia/books/hacking_books_collection/Web Hacking 101.pdf",
     [1,2,3]),
    ("9. Penetration Testing Basics",
     "/home/lacia/books/Hacking-books/9. Penetration Testing Basics.pdf",
     [1,2,3,4]),
    ("10. Network Attacks and Exploitation",
     "/home/lacia/books/Hacking-books/24. Network Attacks and Exploitation.pdf",
     [1,2,3]),
]

outdir = "/home/lacia/.lacia-memory/book-notes"
os.makedirs(outdir, exist_ok=True)

for title, path, chapters in BOOKS:
    slug = title.split(".")[1].strip().replace(" ", "_").lower()[:40]
    print(f"\n{'='*60}")
    print(f"READING: {title}")
    print(f"{'='*60}")
    
    # Check file
    if not os.path.exists(path):
        print(f"  FILE NOT FOUND: {path}")
        continue
    
    result = subprocess.run(["file", path], capture_output=True, text=True)
    if "PDF document" not in result.stdout:
        print(f"  NOT A VALID PDF: {result.stdout.strip()}")
        continue
    
    # Extract pages 1-40 (TOC + intro)
    outfile = os.path.join(outdir, f"{slug}_toc.txt")
    subprocess.run(["pdftotext", "-f", "1", "-l", "40", path, outfile], 
                   capture_output=True)
    size = os.path.getsize(outfile)
    print(f"  TOC extracted: {size} bytes")
    
    # Extract first chapter content
    outfile2 = os.path.join(outdir, f"{slug}_ch1.txt")
    subprocess.run(["pdftotext", "-f", "10", "-l", "60", path, outfile2],
                   capture_output=True)
    size2 = os.path.getsize(outfile2)
    print(f"  Content extracted: {size2} bytes")
    
    # Read key findings
    result = subprocess.run(["head", "-50", outfile], capture_output=True, text=True)
    lines = [l.strip() for l in result.stdout.split('\n') if l.strip() and len(l.strip()) > 20]
    # Find table of contents
    for l in lines[:100]:
        if any(w in l.lower() for w in ['chapter', 'contents', 'introduction', 'overview']):
            print(f"  -> {l[:100]}")

print(f"\n\nDone! Notes saved to {outdir}/")
