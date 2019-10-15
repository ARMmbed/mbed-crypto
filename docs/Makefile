PANDOC = pandoc

default: all

all_markdown = \
	       psa/index.md \
	       psa/accel/index.md \
	       psa/entropy/index.md \
	       psa/se/index.md \
	       # This line is intentionally left blank

html: $(all_markdown:.md=.html)
all: html

.SUFFIXES:
.SUFFIXES: .md .html

.md.html:
	$(PANDOC) -o $@ $<
