PAPER = report
TEX = $(wildcard *.tex)
BIB = bibliography.bib
FLAGS = --shell-escape

.PHONY: all clean

$(PAPER).pdf: $(TEX) $(BIB)
	pdflatex $(FLAGS) $(PAPER)
	bibtex $(PAPER)

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.fls *.fdb_latexmk 
# $(PAPER).pdf 
