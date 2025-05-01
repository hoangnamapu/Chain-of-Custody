#Makefile for the Blockchain Chain of Custody project (bchoc)

PYTHON = python3
EXECUTABLE = bchoc
MAIN_SCRIPT = Main.py


SOURCES = $(MAIN_SCRIPT) Data_Struct.py init.py add.py checkin.py \
          checkout.py remove.py show_cases.py show_history.py \
          show_items.py verify.py Summary.py
          #Add any other .py files here


all: $(EXECUTABLE)

#Rule to create the 'bchoc' executable
#Depends on all source files. If any source file is newer than 'bchoc',
#this rule will run.
$(EXECUTABLE): $(SOURCES)
	@echo "Creating executable $(EXECUTABLE) from $(MAIN_SCRIPT)..."
	cp $(MAIN_SCRIPT) $(EXECUTABLE)
	chmod +x $(EXECUTABLE)
	@echo "$(EXECUTABLE) created successfully."


clean:
	@echo "Cleaning up..."
	rm -f $(EXECUTABLE)
	find . -type d -name __pycache__ -exec rm -rf {} +
	#Optional: Remove common blockchain data file names (Use with caution!)
	@echo "Cleanup complete."

.PHONY: all clean

#This is just here for easy finding for the team and myself.
#export BCHOC_FILE_PATH="chain.bin"
#export BCHOC_PASSWORD_POLICE="P80P"
#export BCHOC_PASSWORD_CREATOR="C67C"
#export BCHOC_PASSWORD_LAWYER="L76L"
#export BCHOC_PASSWORD_EXECUTIVE="E69E"
#export BCHOC_PASSWORD_ANALYST="A65A"