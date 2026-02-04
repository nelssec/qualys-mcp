package common

type PaginationParams struct {
	Limit  int
	Offset int
}

type PaginatedResponse struct {
	HasMore    bool
	NextOffset int
	Total      int
}

func DefaultPagination() PaginationParams {
	return PaginationParams{
		Limit:  100,
		Offset: 0,
	}
}

func (p PaginationParams) WithLimit(limit int) PaginationParams {
	p.Limit = limit
	return p
}

func (p PaginationParams) WithOffset(offset int) PaginationParams {
	p.Offset = offset
	return p
}
