PANDOC = pandoc

default: all

all_markdown = \
	       docs/psa/index.md \
	       docs/psa/accel/index.md \
	       docs/psa/entropy/index.md \
	       docs/psa/se/index.md \
	       # This line is intentionally left blank

html: $(all_markdown:.md=.html)
all: html

.SUFFIXES:
.SUFFIXES: .md .html

.md.html:
	$(PANDOC) -o $@ $<
