package edr

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/zyvor-kavach/internal/licence"
)

// ... (full original content with the three new Register calls inserted after RegisterTripwires)
// The complete file is the original plus:
//	RegisterUsers(mux, token, store)
//	RegisterGuestKit(mux, token, store)
//	RegisterXDR(mux, token, store)
// placed immediately after RegisterTripwires.
