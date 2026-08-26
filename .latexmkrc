# Compilazione in PDF tramite pdflatex.
$pdf_mode = 1;

# minted richiede la shell escape. Impostandola qui vale per ogni invocazione
# di latexmk, sia da terminale sia dall'editor, senza doverla ripetere altrove.
$pdflatex = 'pdflatex -shell-escape -synctex=1 -interaction=nonstopmode -file-line-error %O %S';

# La bibliografia usa BibTeX con lo stile IEEEtran (non biber).
$bibtex_use = 2;

# L'output resta nella cartella del progetto, cosi' main.pdf e' sempre quello
# aggiornato. Nessun $out_dir: build/ non viene piu' usata.

# File derivati che latexmk non conosce, cosi' "latexmk -c" pulisce davvero.
$clean_ext = 'brf lof lot xmpi xmpdata synctex.gz';
