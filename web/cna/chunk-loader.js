/**
 * Chunk Loader - Lazy loading for CNA data
 * 
 * This module provides efficient loading of CNA data in chunks,
 * improving initial page load time for large datasets.
 */

const ChunkLoader = {
  // Configuration
  config: {
    baseUrl: '../data',
    chunksDir: 'chunks',
    manifestFile: 'manifest.json',
    fallbackFile: 'cna_combined.json'
  },
  
  // State
  state: {
    manifest: null,
    loadedChunks: new Map(),
    allData: null,  // Cache of all data once fully loaded
    isChunkedMode: false,
    loading: false
  },
  
  /**
   * Initialize the chunk loader
   * @returns {Promise<Object>} Manifest or fallback indicator
   */
  async init() {
    try {
      // Try to load chunk manifest
      const manifestUrl = `${this.config.baseUrl}/${this.config.chunksDir}/${this.config.manifestFile}`;
      const response = await fetch(manifestUrl);
      
      if (response.ok) {
        this.state.manifest = await response.json();
        this.state.isChunkedMode = true;
        console.log(`ChunkLoader: Initialized with ${this.state.manifest.totalChunks} chunks (${this.state.manifest.totalCNAs} CNAs)`);
        return { mode: 'chunked', manifest: this.state.manifest };
      }
    } catch (error) {
      console.log('ChunkLoader: Chunks not available, using fallback mode');
    }
    
    // Fallback to loading full file
    this.state.isChunkedMode = false;
    return { mode: 'fallback' };
  },
  
  /**
   * Load all data (either from chunks or fallback)
   * @returns {Promise<Array>} All CNA data
   */
  async loadAll() {
    if (this.state.allData) {
      return this.state.allData;
    }
    
    if (!this.state.isChunkedMode) {
      // Load the full file in fallback mode
      const url = `${this.config.baseUrl}/${this.config.fallbackFile}`;
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`Failed to load data: ${response.status}`);
      }
      this.state.allData = await response.json();
      return this.state.allData;
    }
    
    // Load all chunks
    const allItems = [];
    for (let i = 0; i < this.state.manifest.totalChunks; i++) {
      const chunk = await this.loadChunk(i);
      allItems.push(...chunk.items);
    }
    
    this.state.allData = allItems;
    return this.state.allData;
  },
  
  /**
   * Load a specific chunk by index
   * @param {number} chunkIndex - Index of the chunk to load
   * @returns {Promise<Object>} Chunk data with items
   */
  async loadChunk(chunkIndex) {
    if (!this.state.isChunkedMode) {
      throw new Error('Cannot load chunks in fallback mode');
    }
    
    // Return cached chunk if already loaded
    if (this.state.loadedChunks.has(chunkIndex)) {
      return this.state.loadedChunks.get(chunkIndex);
    }
    
    // Validate chunk index
    if (chunkIndex < 0 || chunkIndex >= this.state.manifest.totalChunks) {
      throw new Error(`Invalid chunk index: ${chunkIndex}`);
    }
    
    const chunkFile = this.state.manifest.chunks[chunkIndex];
    const url = `${this.config.baseUrl}/${this.config.chunksDir}/${chunkFile}`;
    
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to load chunk ${chunkIndex}: ${response.status}`);
    }
    
    const chunk = await response.json();
    this.state.loadedChunks.set(chunkIndex, chunk);
    
    return chunk;
  },
  
  /**
   * Load chunks needed for a page range
   * @param {number} startIndex - Start index of items
   * @param {number} endIndex - End index of items
   * @returns {Promise<Array>} Items in the range
   */
  async loadRange(startIndex, endIndex) {
    if (!this.state.isChunkedMode) {
      // In fallback mode, load all and slice
      const allData = await this.loadAll();
      return allData.slice(startIndex, endIndex);
    }
    
    const chunkSize = this.state.manifest.chunkSize;
    const startChunk = Math.floor(startIndex / chunkSize);
    const endChunk = Math.floor((endIndex - 1) / chunkSize);
    
    // Load all needed chunks in parallel
    const chunkPromises = [];
    for (let i = startChunk; i <= endChunk; i++) {
      chunkPromises.push(this.loadChunk(i));
    }
    
    const chunks = await Promise.all(chunkPromises);
    
    // Combine and slice to exact range
    const allItems = [];
    chunks.forEach(chunk => allItems.push(...chunk.items));
    
    // Calculate offset within combined chunks
    const combinedStartIndex = startChunk * chunkSize;
    const localStart = startIndex - combinedStartIndex;
    const localEnd = localStart + (endIndex - startIndex);
    
    return allItems.slice(localStart, localEnd);
  },
  
  /**
   * Load initial page of data (first chunk)
   * @returns {Promise<Object>} Initial data and metadata
   */
  async loadInitial() {
    if (!this.state.isChunkedMode) {
      const allData = await this.loadAll();
      return {
        items: allData,
        totalItems: allData.length,
        chunked: false
      };
    }
    
    // Load first chunk for initial display
    const firstChunk = await this.loadChunk(0);
    
    return {
      items: firstChunk.items,
      totalItems: this.state.manifest.totalCNAs,
      chunked: true,
      loadedCount: firstChunk.items.length
    };
  },
  
  /**
   * Preload chunks near a page for smoother navigation
   * @param {number} currentChunk - Current chunk index
   * @param {number} preloadCount - Number of chunks to preload
   */
  async preloadNearby(currentChunk, preloadCount = 1) {
    if (!this.state.isChunkedMode) return;
    
    const preloadPromises = [];
    
    for (let offset = 1; offset <= preloadCount; offset++) {
      // Preload next chunks
      if (currentChunk + offset < this.state.manifest.totalChunks) {
        preloadPromises.push(this.loadChunk(currentChunk + offset));
      }
      // Preload previous chunks
      if (currentChunk - offset >= 0) {
        preloadPromises.push(this.loadChunk(currentChunk - offset));
      }
    }
    
    // Fire and forget - don't await
    Promise.all(preloadPromises).catch(() => {
      // Ignore preload errors
    });
  },
  
  /**
   * Get total number of items
   * @returns {number} Total item count
   */
  getTotalCount() {
    if (this.state.manifest) {
      return this.state.manifest.totalCNAs;
    }
    if (this.state.allData) {
      return this.state.allData.length;
    }
    return 0;
  },
  
  /**
   * Check if chunked mode is active
   * @returns {boolean} True if using chunks
   */
  isChunked() {
    return this.state.isChunkedMode;
  },
  
  /**
   * Get loaded chunks count
   * @returns {number} Number of loaded chunks
   */
  getLoadedChunksCount() {
    return this.state.loadedChunks.size;
  },
  
  /**
   * Clear cache and reset state
   */
  reset() {
    this.state.manifest = null;
    this.state.loadedChunks.clear();
    this.state.allData = null;
    this.state.isChunkedMode = false;
    this.state.loading = false;
  }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ChunkLoader;
}
